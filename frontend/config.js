// PolicyLens frontend configuration.
//
// API_URL is where the frontend sends policies for analysis.
//
// - Local testing with scripts/dev_server.py: leave this as "/analyze"
//   (the dev server serves this page and the API from the same origin).
// - Amplify deployment: set this to your Lambda Function URL, e.g.
//   "https://abc123.lambda-url.us-east-1.on.aws/"
//
// This is the ONLY value you must change before deploying.
window.POLICYLENS_CONFIG = {
  API_URL: "/analyze",
};
