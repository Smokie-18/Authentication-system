import express from 'express' ;
import morgan from "morgan";
import authRouter from './routers/auth.routes.js';
import CookieParser from 'cookie-parser';

const app = express() ;

app.use(express.json());
app.use(morgan("dev"));
app.use(CookieParser());


app.use("/api/auth" , authRouter) ;
export default app ;