var assert = require('assert');
var EdgeAuth = require("../EdgeAuth")
var edge_auth = new EdgeAuth({salt:"foobar",key:"aaaa1111"},true);
var start_time = (new Date("01/01/2014")).getTime();
var end_time = (new Date("01/01/2014")).getTime();
var window = end_time - start_time;
var token_1 = edge_auth.generateToken({url:"/foo/bar/1",start_time: start_time, window: window});
console.log(token_1); 