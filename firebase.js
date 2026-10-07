const admin = require("firebase-admin");

let initialized = false;

function initFirebase() {
  if (initialized) return admin;

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (!raw) {
    console.warn(
      "FIREBASE_SERVICE_ACCOUNT_JSON не задан. FCM отключён."
    );
    return null;
  }

  try {
    const serviceAccount = JSON.parse(raw);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });

    initialized = true;

    console.log("Firebase Admin успешно запущен.");

    return admin;
  } catch (error) {
    console.error(
      "Ошибка Firebase Admin:",
      error.message
    );

    return null;
  }
}

function firebase() {
  return initFirebase();
}

module.exports = { firebase };
