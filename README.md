# loopback-jwt-advanced

[![License](https://img.shields.io/npm/l/loopback-jwt-advanced.svg)](LICENSE)
[![Version](https://img.shields.io/npm/v/loopback-jwt-advanced.svg)](https://www.npmjs.com/package/loopback-jwt-advanced)
[![Downloads](https://img.shields.io/npm/dm/loopback-jwt-advanced.svg)](https://www.npmjs.com/package/loopback-jwt-advanced)

`loopback-jwt-advanced` is a node express middleware plugin to map [Json Web tokens](https://www.jwt.io) and [Loopback](https://strongloop.com/) users.
In addition to the original [loopback-jwt](https://github.com/whoGloo/loopback-jwt) it enabled quite some new options and even passing generic options to the underlying [express-jwt](https://github.com/auth0/express-jwt).

## Example usage

```sh
export JWT_USER_PASSWORD="SOME_RANDOM_SECRET";
```

```js
const loopbackJWT = require("loopback-jwt-advanced");

const auth = loopbackJWT(app, {
  verify: function (req) {
    var jwt = req.user;
    if ("some custom verification fails") { throw new Error("Token invalid."); }
  },
  beforeCreate: function (userObj, req) {
    var jwt = req.user;
    // add custom fields to the user object within the database
    userObj.emailVerified = jwt.email_verified;
    userObj.username = jwt.nickname;
    userObj.remoteId = jwt.sub;
  }
});

app.use("/<path>", auth.authenticated);

app.use(function (err, req, res, next) {
  // beautify error for loopback.errorHandler()
  if (err.name === "UnauthorizedError") { err = {status: 401, message: "Missing or invalid token"}; }
  next(err);
});
```

## Getting Started

loopback-jwt-advanced is a simple middleware to map jwt with loopback. It is assumed that a jwt has been passed in the request.

### Installation

```sh
npm install loopback-jwt-advanced --save
```

### Usage

`var auth = require("loopback-jwt-advanced")(app, options, jwtOptions);`

`options` may contain the following properties:
 * `[String] model` - default: `"User"`; loopback model used for User instances.
 * `[String] identifier` - default: `"email"`; jwt property to use as User identifier.
 * `[String] key` - default: `"email"`; loopback model property to store the User identifier at.
 * `[String] password` - default: `process.env["JWT_USER_PASSWORD"]`; pseudo-password to use for User instances within db.
 * `[Array] unless` - default: `[]`; exceptions for the `express-jwt` paths, see [express-unless](https://github.com/jfromaniello/express-unless) for syntax.
 * `[Function(req) throws Error] verify` - additional JWT Token verification can be performed within.
 * `[[[userObj|void 0] Promise] Function(userObj, req)] beforeCreate` - the user object as created within db can be expanded within.

`jwtOptions` is passed to [`express-jwt`](https://github.com/auth0/express-jwt), check it out for all options. 
 * `[String|Function] secret` - required; type depends on algorithm in use
 * `[String[]] algorithms` - default: `["RS256", "HS256"]`

## Contributors

 https://github.com/PainPointSolutions/loopback-jwt-advanced/graphs/contributors

## License

[MIT](LICENSE)
