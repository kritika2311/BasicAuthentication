import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieparser from "cookie-parser";
import jwt from "jsonwebtoken";
import { STATUS_CODES } from "http";
import bcrypt from "bcrypt";

const app = express();
mongoose
    .connect("mongodb://127.0.0.1:27017", {
        dbName: "backend",
    })
    .then(() => console.log("Database Connected"))
    .catch((e) => console.log(e));

const userschema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
});

const User = mongoose.model("User", userschema);

app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieparser());

//settinng up view enginez
app.set("view engine", "ejs");

//handler
const isauthenticated = async (req, res, next) => {
    const { token } = req.cookies;
    if (token) {
        try {
            const decodedtoken = jwt.verify(token, "kritikaencryption");
            req.user = await User.findById(decodedtoken._id);
            console.log(req.user);
            next();
        } catch (error) {
            console.error("Error while fetching user:", error);
            res.redirect("/login");
        }
    }
    else {
        res.redirect("/login");
    }
};


//API's
app.get("/", isauthenticated, (req, res) => {
    res.render("logout", { name: req.user.name });

});


app.get("/register", (req, res) => {
    res.render("register");
});


app.get("/login", (req, res) => {
    res.render("login");
});


app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    let user = await User.findOne({ email });
    if (!user) {
        return res.redirect("/register");
    }
    const isPass = await bcrypt.compare(password, user.password);
    if (!isPass) {
        return res.render("login", { email, message: "Incorrect password" });
    }
    const token = jwt.sign({ _id: user._id }, "kritikaencryption")
    res.cookie("token", token, {
        httpOnly: true, expires: new Date(Date.now() + 60 * 1000)
    });
    res.redirect("/")
})


app.post("/register", async (req, res) => {
    console.log(req.body)
    const { name, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) {
        return res.redirect("/login");
    }
    const hashPassword = await bcrypt.hash(password, 10);
    user = await User.create({ name, email, password: hashPassword });
    const token = jwt.sign({ _id: user._id }, "kritikaencryption")
    res.cookie("token", token, {
        httpOnly: true, expires: new Date(Date.now() + 60 * 1000)
    });
    res.redirect("/")
});


app.get("/logout", (req, res) => {
    res.cookie("token", null, { expires: new Date(Date.now()), httpOnly: true })
    res.redirect("/")
    console.log("deleted")
})




app.listen(5000, () => {
    console.log("Server is working")
});