use super::*;
use futures::{StreamExt, stream};
use hickory_proto::{op::Query, rr::RecordType};

impl Engine {
    pub(crate) async fn warmup(self: Arc<Self>) {
        let settings = &self.config.warmup;
        let mut questions = Vec::new();
        if settings.history_limit > 0 {
            // Bound startup I/O even on instances with millions of retained queries.
            let recent = sqlx::query_as::<_, (String, String)>(
                "SELECT domain,qtype FROM (
                    SELECT domain,qtype,outcome FROM query_log ORDER BY id DESC LIMIT 10000
                 ) WHERE outcome IN ('doh','recursive','gfw_doh','gfw_fallback_doh')
                   AND qtype IN ('A','AAAA','HTTPS')
                 GROUP BY domain,qtype ORDER BY count(*) DESC,domain,qtype LIMIT ?",
            )
            .bind(settings.history_limit as i64)
            .fetch_all(&self.store.pool)
            .await;
            match recent {
                Ok(rows) => {
                    for (domain, kind) in rows {
                        if let (Ok(domain), Ok(kind)) = (normalize_domain(&domain), kind.parse()) {
                            questions.push((domain, kind));
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "could not load popular DNS questions"),
            }
        }
        for domain in &settings.domains {
            for kind in [RecordType::A, RecordType::AAAA] {
                questions.push((domain.clone(), kind));
            }
        }
        let mut seen = HashSet::new();
        questions.retain(|q| seen.insert(q.clone()));
        let results = stream::iter(questions)
            .map(|(domain, kind)| {
                let engine = &self;
                async move {
                    let policy = engine.policy.load_full();
                    if policy.local.iter().any(|r| r.domain == domain)
                        || (!matches_domain(&policy.allow, &domain)
                            && matches_domain(&policy.block, &domain))
                        || policy.forward.iter().any(|(suffix, _)| {
                            domain == *suffix || domain.ends_with(&format!(".{suffix}"))
                        })
                    {
                        return false;
                    }
                    let Ok(name) = Name::from_ascii(format!("{domain}.")) else {
                        return false;
                    };
                    let mut request = Message::query();
                    request.metadata.recursion_desired = true;
                    request.add_query(Query::query(name, kind));
                    matches!(
                        engine
                            .routed_lookup(&engine.features.current.load_full(), &request, &domain)
                            .await,
                        Ok(Ok(_))
                    )
                }
            })
            .buffer_unordered(2);
        let resolved = results.filter(|ok| std::future::ready(*ok)).count().await;
        tracing::info!(
            resolved,
            candidates = seen.len(),
            "DNS startup warmup finished"
        );
    }
}
