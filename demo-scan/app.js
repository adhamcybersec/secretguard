// Application configuration
const config = {
  database: {
    url: "postgres://dbuser:dbpass123@localhost:5432/mydb"
  },
  
  google: {
    apiKey: "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
  },
  
  auth: {
    jwtSecret: "aB3$xY9!mN2@pQ7&kL5#wR8^tU4*iO6(vE1)sD0%"
  }
};

// Authorization header
const headers = {
  'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
};

module.exports = config;
