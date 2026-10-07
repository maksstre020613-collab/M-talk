const { initializeApp, cert } = require("firebase-admin/app");
const { getMessaging } = require("firebase-admin/messaging");

let firebaseApp = null;

function initFirebase() {
  if (firebaseApp) {
    return {
      messaging: () => getMessaging(firebaseApp)
    };
  }

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (!raw) {
    console.warn(
      "FIREBASE_SERVICE_ACCOUNT_JSON не задан. FCM отключён."
    );
    return null;
  }

  try {
    const serviceAccount = JSON.parse(raw);

    firebaseApp = initializeApp({
      credential: cert(serviceAccount)
    });

    console.log("Firebase Admin успешно запущен.");

    return {
      messaging: () => getMessaging(firebaseApp)
    };
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
