import express from 'express'
const app = express()
import 'dotenv/config';
import connectDB from './config/connectDB.js';
const port = process.env.PORT || 3000;
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import setRoute from './routes/routes.js';

// middlewares
const middlewares = [
    cors({
        origin: [process.env.FRONT_URL, 'http://localhost:5173'],
        credentials: true
    }),
    helmet(),
    morgan('dev'),
    express.json(),
    express.urlencoded(),
];

app.use(middlewares);

// routes
setRoute(app);

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ message: "Page not found" });
});
// Error handler
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(500).json({ message: "Internal Server Error" });
});
app.listen(port, () => {
    try {
        console.log(`Server is running on port ${port}`);
        connectDB();
    } catch (error) {
        console.log(error.message);
    };
});