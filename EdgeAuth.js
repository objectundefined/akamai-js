var querystring = require('querystring');
var assert = require('assert');
var format = require('util').format;
var crypto = require('crypto');
var _s = require('underscore.string');
var field_mappings = { expiration: 'exp', start_time: 'st', session_id: 'id' };
var _ = require('underscore');

module.exports = EdgeAuth;

function EdgeAuth(default_token_opts, debug) {
  this._defaults = default_token_opts || {};
  this._debug = !!debug;
}

EdgeAuth.prototype.generateToken = function ( conf ) {
  // wrap configuration obj in instance of AkamaiTokenConfig
  // which asserts errors if present
  var tc = _.extend({},this._defaults,conf||{});
  var token_config = new AkamaiTokenConfig(tc);
  // determine the values for hashing
  var mtoken = ([
    token_config.getField('ip'),
    token_config.getField('start_time'),
    token_config.getField('expiration'),
    token_config.getField('acl'),
    token_config.getField('session_id'),
    token_config.getField('data')
  ]).join('');
  var mtoken_digest = ([
    mtoken,
    token_config.getField('url'),
    token_config.getField('salt')
  ]).join('');
  // Produce the hmac and include in the output template
  var enc_key = token_config.get('key');
  var signing_value = _s.rstrip(mtoken_digest, token_config.get('field_delimiter'));
  var algo = token_config.get('algo');
  var my_hmac = crypto.createHmac(algo, enc_key).update(signing_value).digest('hex');
  // log if _debug enabled
  if (this._debug) {
    console.log("SIGNING VALUE: %s" , signing_value );
    console.log("PRODUCES: %s" , my_hmac );
  }
  // return signed querystring
  return format("%s%s=%s", mtoken, 'hmac', my_hmac ); 
}

// Note- times are in MS, idiomatic to Javascript

function AkamaiTokenConfig(conf_obj) {
  var conf = this.conf = {
    _start_time: Date.now(),
    _key: 'aabbccddeeff00112233445566778899',
    _algo: 'sha256',
    _acl: '',
    _url: '',
    _window: 300000, // window in ms to conform to js
    ip: '', // todo: provide get/set and validate ipv4/ipv6
    session_id: '',
    data: '',
    salt: '',
    field_delimiter: '~',
    early_url_encoding: false
  };
  
  Object.defineProperty(conf,'start_time',{
    get: function () { return conf._start_time },
    set: function ( val ) {
      var st_date = new Date(val);
      var st_time = st_date.getTime();
      var valid = !isNaN(st_time) && st_time > 0 || st_time < 4294967295000;
      assert(valid, "start_time invalid or out of range");
      conf._start_time = st_time;
    }
  });
  Object.defineProperty(conf,'window',{
    get: function () { return conf._window },
    set: function ( val ) {
      assert(!isNaN(val), 'Window must be a Number');
      conf._window = val;
    }
  });
  Object.defineProperty(conf,'key',{
    get: function () { return conf._key.toString('hex') },
    set: function ( val ) {
      var valid = true;
      var key;
      try {
        key = new Buffer(val,'hex');
      } catch(e) {
        valid = false;
      }
      assert(valid,'Key must be valid hex string');
      conf._key = key;
    }
  });
  Object.defineProperty(conf,'algo',{
    get: function () { return conf._algo },
    set: function ( val ) {
      var valid = ['md5','sha1','sha256'].indexOf(val) >= 0;
      assert(valid,"Invalid algorithm");
      conf._algo = val;
    }
  });
  Object.defineProperty(conf,'acl',{
    get: function () { return conf._acl },
    set: function ( val ) {
      var valid = !conf.url;
      assert(valid,"Cannot set both an acl and url at the same time");
      conf._acl = val;
    }
  });  
  Object.defineProperty(conf,'url',{
    get: function () { return conf._url },
    set: function ( val ) {
      var valid = !conf.acl;
      assert(valid,"Cannot set both an acl and url at the same time");
      conf._url = val;
    }
  });
  // apply passed-in conf through getters and setters
  Object.keys(conf_obj||{}).forEach(function(k){
    conf[k] = conf_obj[k];
  });
  // quick sanity check
  assert(this.conf.acl || this.conf.url, "Must specify either an ACL or a URL and not both");
  
}

AkamaiTokenConfig.prototype.encode = function(value) {
  if ( this.conf.early_url_encoding ) {
    return querystring.encode({ x: value }).split('=')[1];
  } else {
    return value;
  }
}

AkamaiTokenConfig.prototype.getField = function (field_name) {
  var field_val = this.conf[field_name];
  var repr_name = field_mappings.hasOwnProperty(field_name) ? field_mappings[field_name] : field_name ;
  if (field_name == 'expiration'){
    field_val = parseInt(this.conf.start_time/1000) + parseInt(this.conf.window/1000);
  } else if (field_name == 'start_time'){
    field_val = parseInt(this.conf.start_time/1000);
  } else if (field_name == 'acl') {
    if (this.conf.acl) {
      field_val = this.encode(this.conf.acl);
    } else if (!this.conf.url){
      field_val = this.encode('/*');
    } else {
      field_val = null;
    }
  } else if (['url','ip','session_id','data'].indexOf(field_name) >=0 ) {
    field_val = this.encode(this.conf[field_name]);
  }
  
  if (field_val) {
    return format("%s=%s%s", repr_name, field_val, this.conf.field_delimiter);    
  } else {
    return '';
  }
}

AkamaiTokenConfig.prototype.get = function ( field_name ) {
  return this.conf[field_name]; // goes through getter
};

AkamaiTokenConfig.prototype.set = function ( field_name, val ) {
  return this.conf[field_name] = val; // goes through setter
};
