import app from "./api/index.js";

const PORT = process.env.PORT || 5000;

(async () => {
  try {
    app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
  } catch (error) {
    console.error("❌ Failed to connect to DB", error);
    process.exit(1);
  }
})();
