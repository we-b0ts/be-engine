//! Validate one published execution or a Source-only case batch without borrowing
//! another API's Target clocks or witness identities.
use super::*;

pub(super) fn verify(
    root: &Path,
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) -> Result<()> {
    for (case_id, directory) in bundle.cases.clone() {
        let request = bundle.request(&directory.join("request.json"))?;
        let method = request["method"]
            .as_str()
            .context("Source request method unavailable")?;
        let uri = request["uri"]
            .as_str()
            .context("Source request URI unavailable")?;
        let path = uri
            .parse::<hyper::Uri>()
            .context("invalid Source URI")?
            .path()
            .to_string();
        let source_body = capture(&request["body"])
            .ok()
            .and_then(|bytes| crate::json_value::parse(&bytes));
        let native_applicable = crate::primary_protocol::assertion::native::selected(
            policy,
            method,
            &path,
            source_body.as_ref(),
        );
        let native_response = native_applicable
            .iter()
            .copied()
            .filter(|rule| api::is_response(rule))
            .collect::<Vec<_>>();
        if native_response
            .iter()
            .any(|r| selected.contains(&r.rule.id))
        {
            api::verify(
                root,
                bundle,
                &case_id,
                &directory,
                &request,
                policy.global_json.as_ref(),
                &native_response,
                result,
            )?;
        }
    }
    Ok(())
}
