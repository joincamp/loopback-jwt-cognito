/*! The MIT License (MIT)
 * Copyright (c) 2017 PainPoint Solutions UG (Haftungsbeschränkt)
 * Copyright (c) 2016 Julian Lyndon-Smith (julian@whogloo.io), whoGloo inc
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
"use strict";

var _ = require("lodash");
var jwt = require("express-jwt");
var Promise = require("bluebird");

var loopbackTokenPromises = {};
var loopbackToken = {};

module.exports = function (app, opts, jwtOpts) {
  var password = opts.password === void 0 ? process.env["JWT_USER_PASSWORD"] : opts.password;

  if (jwtOpts.secret == null) { throw new Error("'secret' must be supplied within jwtOpts."); }
  if (password == null) {
    throw new Error("'password' must be supplied. You may also specify an environment variable 'JWT_USER_PASSWORD' instead.");
  }

  var jwtOptions = _.defaults(jwtOpts, {algorithms: ["RS256", "HS256"]});
  var options = _.defaults(opts, {
    model: "User", identifier: "email", key: "email", password: password,
    userProperty: jwtOptions.userProperty || jwtOptions.requestProperty || "user"
  });

  var checkJwt = jwt(jwtOptions).unless({path: options.unless || []});

  return {authenticated: [checkJwt, _.partial(mapUser, app, options)]};
};

/*==================================================== Functions  ====================================================*/

function mapUser(app, options, req, res, next) {
  var model = app.models[options.model];
  if (!req[options.userProperty]) { return next(); }

  if (typeof options.verify === "function") { try { options.verify(req); } catch (e) { return next(e); } }

  var id = req[options.userProperty][options.identifier];

  if (loopbackToken.hasOwnProperty(id)) {
    req.accessToken = loopbackToken[id];
    next();
  } else {
    if (!loopbackTokenPromises.hasOwnProperty(id)) {
      loopbackTokenPromises[id] = loginCreate(model, options, id, req)
          .then(function (token) {
            delete loopbackTokenPromises[id];
            return loopbackToken[id] = token;
          });
    }
    loopbackTokenPromises[id]
        .then(function (token) {
          req.accessToken = token;
          next();
        }, next);
  }
}

function loginCreate(model, options, id, req) {
  return login(model, options, id)
      .catch(function (err) {
        if (err.message === "login failed") { return Promise.reject(err); }
        return create(model, options, id, req)
            .then(_.partial(login, model, options, id));
      });
}

function login(model, options, id) {
  var credentials = {password: options.password};
  credentials[options.key] = id;
  return model.login(credentials);
}

function create(model, options, id, req) {
  var userObj = {password: options.password};
  userObj[options.key] = id;
  var promise;
  if (typeof options.beforeCreate === "function") {
    promise = Promise.resolve(options.beforeCreate(userObj, req));
  } else {
    promise = Promise.resolve(userObj);
  }
  return promise.then(function (obj) { return model.create(obj === void 0 ? userObj : obj); });
}
