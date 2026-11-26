use super::*;
pub(super) use crate::resolver::record_type_label as type_label;
use axum::extract::ConnectInfo;
use hickory_proto::{
    op::{Edns, Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType},
};
use std::net::SocketAddr;

#[derive(Deserialize)]
pub(crate) struct Input {
    domain: String,
    qtype: String,
    #[serde(default)]
    dnssec_ok: bool,
    #[serde(default)]
    adguard: bool,
}

pub(super) fn record_type(input: &str) -> Option<RecordType> {
    let input = input.trim().to_ascii_uppercase();
    let code = input.strip_prefix("TYPE").unwrap_or(&input);
    code.parse::<u16>()
        .map(RecordType::from)
        .ok()
        .or_else(|| input.parse().ok())
        .or_else(|| {
            let code = match input.as_str() {
                "LOC" => 29,
                "OPT" => 41,
                "IXFR" => 251,
                "URI" => 256,
                "EUI48" => 108,
                "EUI64" => 109,
                _ => return None,
            };
            Some(RecordType::from(code))
        })
}

pub(super) fn rcode_label(code: ResponseCode) -> String {
    match code {
        ResponseCode::Unknown(code) => format!("RCODE{code}"),
        _ => format!("{code:?}").to_ascii_uppercase(),
    }
}

#[derive(Serialize)]
struct AnswerRecord {
    name: String,
    qtype: String,
    ttl: u32,
    data: String,
}

impl From<&Record> for AnswerRecord {
    fn from(record: &Record) -> Self {
        let data = match &record.data {
            RData::Unknown { rdata, .. } => {
                format!(
                    "\\# {} {}",
                    rdata.anything.len(),
                    hex::encode(&rdata.anything)
                )
            }
            data => data.to_string(),
        };
        Self {
            name: record.name.to_utf8(),
            qtype: type_label(record.record_type()),
            ttl: record.ttl,
            data,
        }
    }
}

#[derive(Serialize)]
pub(super) struct DnsResponse {
    rcode: String,
    ad: bool,
    answers: Vec<AnswerRecord>,
    authorities: Vec<AnswerRecord>,
    additionals: Vec<AnswerRecord>,
}

impl From<&Message> for DnsResponse {
    fn from(message: &Message) -> Self {
        Self {
            rcode: rcode_label(message.metadata.response_code),
            ad: message.metadata.authentic_data,
            answers: message.answers.iter().map(AnswerRecord::from).collect(),
            authorities: message.authorities.iter().map(AnswerRecord::from).collect(),
            additionals: message.additionals.iter().map(AnswerRecord::from).collect(),
        }
    }
}

pub(super) async fn test(
    State(s): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(input): Json<Input>,
) -> Reply {
    check_same_origin(&h)?;
    let id = dns::authenticate_active(&s, &h).await?;
    run(&s, peer, &h, input, Some(id)).await
}

pub(crate) async fn run(
    s: &ApiState,
    peer: SocketAddr,
    headers: &HeaderMap,
    input: Input,
    user_id: Option<i64>,
) -> Reply {
    let domain = input.domain.trim();
    if domain.is_empty() || domain.len() > 1024 {
        return Err(bad("请输入有效的域名"));
    }
    let mut name = Name::from_utf8(domain).map_err(|_| bad("请输入有效的域名"))?;
    name.set_fqdn(true);
    let qtype =
        record_type(&input.qtype).ok_or_else(|| bad("记录类型无效，可使用 A 或 TYPE123 等格式"))?;
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(name.clone(), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232).set_dnssec_ok(input.dnssec_ok);
    query.edns = Some(edns);
    let lookup_error = || {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "DNS 解析测试暂时不可用".to_owned(),
        )
    };
    let wire = query.to_vec().map_err(|_| lookup_error())?;
    let peer = crate::api::doh_client(
        s,
        peer,
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
    );
    let result = s
        .engine
        .answer_with_diagnostics(
            &wire,
            peer,
            if user_id.is_some() { "doh" } else { "test" },
            user_id,
            user_id.is_none() && input.adguard,
        )
        .await
        .map_err(|_| lookup_error())?;
    let response = Message::from_vec(&result.wire).map_err(|_| lookup_error())?;
    Ok(Json(json!({
        "domain": name.to_utf8(), "qtype": type_label(qtype),
        "duration_ms": result.duration_ms,
        "block_reason": result.block_reason,
        "response": DnsResponse::from(&response)
    })))
}
