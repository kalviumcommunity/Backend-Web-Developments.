
'use strict';

const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { users, nextId } = require('../data');

async function verifyCallback(accessToken, refreshToken, profile, done) {
  try {
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const name = profile.displayName;

    // 1. Returning OAuth user: match by Google ID first.
    let user = users.find((u) => u.googleId === googleId);

    if (user) {
      return done(null, user);
    }

    // 2. Existing local account: link only if email is verified.
    user = users.find((u) => u.email === email);

    if (user) {
      if (profile._json.email_verified !== true) {
        return done(null, false);
      }

      user.googleId = googleId;
      return done(null, user);
    }

    // 3. Brand-new user: always assign the lowest role.
    const newUser = {
      id: nextId(),
      googleId,
      email,
      name,
      role: 'member',
    };

    users.push(newUser);
    return done(null, newUser);
  } catch (error) {
    return done(error);
  }
}

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || 'test-client-id',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'test-client-secret',
      callbackURL: '/auth/google/callback',
    },
    verifyCallback,
  ),
);

module.exports = { passport, verifyCallback };
