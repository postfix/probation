struct Context;
struct Response;

fn validate_host_and_registry(_: u64, _: u64) {}
fn build_context(_: u64, _: u64) -> Context { Context }
fn check_read_policy(_: &Context) {}
fn send_read(_: &Context) -> Response { Response }
fn validate_action_origin(_: &Context) {}
fn send_action(_: &Context) -> Response { Response }
fn mark_revoked(_: u64) {}
fn invalidate_cache(_: u64) {}

fn resolve_context(host: u64, registry: u64) -> Context {
    validate_host_and_registry(host, registry);
    build_context(host, registry)
}

fn serve_package_read(context: &Context) -> Response {
    check_read_policy(context);
    send_read(context)
}

fn forward_registry_action(context: &Context) -> Response {
    validate_action_origin(context);
    send_action(context)
}

fn revoke_host(host: u64) {
    mark_revoked(host);
    invalidate_cache(host);
}
