// Viewer-request CloudFront Function. It copies the Host the viewer asked
// for into x-litelogin-host, the only place the Auth Lambda reads the
// login host from: the origin request carries the function URL's own Host.
// Setting the header here also replaces any value the viewer sent.
function handler(event) {
  var request = event.request;
  var host = request.headers.host ? request.headers.host.value : '';
  host = host.toLowerCase();
  var colon = host.indexOf(':');
  if (colon !== -1) {
    host = host.substring(0, colon);
  }
  if (host.length > 0 && host.charAt(host.length - 1) === '.') {
    host = host.substring(0, host.length - 1);
  }
  request.headers['x-litelogin-host'] = { value: host };
  return request;
}
