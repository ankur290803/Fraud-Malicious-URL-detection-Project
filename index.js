
const express = require("express");
const path = require("path");
const validateURL = require("./urlValidator");

const app = express();
const PORT = 3000;

// Set EJS as the template engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware
app.use(express.urlencoded({ extended: false }));

// Home page
app.get("/", (req, res) => {
    res.render("index", { result: null, submittedURL: "" });
});

// Check submitted URL
app.post("/check-url", (req, res) => {
    const submittedURL = req.body.url || "";
    const result = validateURL(submittedURL);

    res.render("index", {
        result,
        submittedURL
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
