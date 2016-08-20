/*
 * bearerAuth Policy
 *
 * Policy for authorizing API requests. The request is authenticated if the
 * it contains the accessToken in header, body or as a query param.
 * Unlike other strategies bearer doesn't require a session.
 * Add this policy (in config/policies.js) to controller actions which are not
 * accessed through a session. For example: API request from another client
 *
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */

'use strict';

module.exports = function (req, res, next) {
  var auth = req.headers.authorization;
  if (!auth || auth.search('Bearer ') !== 0) {
    return next();
  }
  return passport.authenticate('bearer', { session: false })(req, res, next);
};