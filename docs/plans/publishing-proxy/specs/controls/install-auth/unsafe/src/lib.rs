struct Request;
struct Response;
struct InstallAccess;

fn admit_install(_: &Request) -> Result<InstallAccess, ()> { Ok(InstallAccess) }
fn unchecked_access() -> InstallAccess { InstallAccess }
fn serve_package_read(_: &InstallAccess, _: &Request) -> Response { Response }

fn dispatch_registry_request(request: &Request) -> Result<Response, ()> {
    let access = unchecked_access();
    Ok(serve_package_read(&access, request))
}
