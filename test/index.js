var assert = require('assert');
var EdgeAuth = require("../EdgeAuth")
var edge_auth = new EdgeAuth({salt:"foobar",key:"aaaa1111"},true);
var token_1 = edge_auth.generateToken({url:"/foo/bar/1",session_id:"12345", start_time: new Date("01/01/2014"), expire_time: new Date("01/01/2015")});
console.log(token_1); 