/// How the bytes travel. The default is HTTPS outcalls through the management canister --
/// the one transport that exists on moxzi hosts and on the IC alike; a host with its own
/// HTTP (the browser's fetch) supplies an `Http` of its own.
module {
  public type Response = { status : Nat; body : Blob };

  public type Http = {
    post : (url : Text, body : Blob) -> async* Response;
    get : (url : Text) -> async* Response;
  };

  type HttpHeader = { name : Text; value : Text };
  type HttpResponse = { status : Nat; headers : [HttpHeader]; body : Blob };
  type Management = actor {
    http_request : shared ({
      url : Text;
      max_response_bytes : ?Nat64;
      method : { #get; #head; #post };
      headers : [HttpHeader];
      body : ?Blob;
      transform : ?{ function : shared query ({ response : HttpResponse; context : Blob }) -> async HttpResponse; context : Blob };
      is_replicated : ?Bool;
    }) -> async HttpResponse;
  };

  /// `cycles` rides on every request (0 on an off-chain host; the IC's price on-chain).
  public func outcalls(cycles : Nat, maxResponseBytes : Nat64) : Http {
    let ic : Management = actor "aaaaa-aa";
    func request(method : { #get; #post }, url : Text, body : ?Blob) : async* Response {
      let r = await (with cycles = cycles) ic.http_request({
        url;
        max_response_bytes = ?maxResponseBytes;
        method;
        headers = [{ name = "content-type"; value = "application/cbor" }];
        body;
        transform = null;
        is_replicated = null;
      });
      { status = r.status; body = r.body }
    };
    {
      post = func(url : Text, body : Blob) : async* Response { await* request(#post, url, ?body) };
      get = func(url : Text) : async* Response { await* request(#get, url, null) };
    }
  };
}
