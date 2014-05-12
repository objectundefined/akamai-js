var assert = require('assert');
var crypto = require('crypto');

module.exports = UrlAuth ;

function UrlAuth ( opts ) {
  this.salt = opts && opts.salt;
  this.param = opts && opts.param;
  this.extract = opts && opts.extract;
  this.base_url = opts && opts.base_url;
  assert(
    typeof this.base_url == "string",
    "A base_url must be provided to generate valid urls from a uri path."
  )
}

UrlAuth.prototype.signUrl = function ( path , expiration_date ) {
  var now = Date.now();
  var future = expiration_date && expiration_date.getTime && expiration_date.getTime();
  assert(
    future > now,
    "An expiration date must be passed in that is greater than now"
  );
  var param = this.param;
  var salt = this.salt;
  var extract = this.extract;
  var time = parseInt(now/1000);
  var window = parseInt(future/1000) - time ;
  return this.base_url + genUrl(path, param, window, salt, extract, time );
}

function genUrl (url_str, opt_param_str, window_num, salt_str, opt_extract_str, time_num) {
  
  var param_str = opt_param_str && opt_param_str.length ? opt_param_str : "__gda__";
  var extract_str = opt_extract_str && opt_extract_str.length ? opt_extract_str : "";
  var window_int = parseInt(window_num);
  var time_int = parseInt(time_num) ? parseInt(time_num) : parseInt(Date.now()/1000);
  var expires_int = window_int + time_int;
  var appender = url_str.indexOf("?") >= 0 ? "&" : "?";
  var window_valid = 
  
  assert(
    salt_str && salt_str.length,
    "Salt must be provided"
  );
  assert(
    param_str.length > 5 || param_str.length < 12,
    'Url params must not be longer than 12 chars or shorder than 5'
  );
  assert(
    !isNaN(window_int),
    'Window must be a number of seconds'
  );
  
  var token_str = genToken( url_str, salt_str, expires_int, extract_str );
  
  return url_str + appender + param_str + "=" + expires_int + "_" + token_str;
  
}

function genToken (url_str, salt_str, expires_int, extract_str) {
  var initial_hash = crypto.createHash('md5')
    .update(String.fromCharCode(expires_int & 0xff))
    .update(String.fromCharCode((expires_int >> 8) & 0xff))
    .update(String.fromCharCode((expires_int >> 16) & 0xff))
    .update(String.fromCharCode((expires_int >> 24) & 0xff))
    .update(url_str)
    .update(extract_str)
    .update(salt_str)
    .digest();
  var salted_hash = crypto.createHash('md5').update(salt_str).update(initial_hash);
  return salted_hash.digest('hex');
}