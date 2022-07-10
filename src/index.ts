require('dotenv').config();

/**
 * Simple implementation of sessions using cookies with Express and TypeScript,
 * when using sessions and cookies you should be aware of what are the best 
 * practices to it (like using HTTPS cookies, providing a secret to sign session
 * cookies or generating very long strings for session ID, etcetera), which I 
 * didn't implement in here, so keep that in mind.
 *
 * @author Luis Barraza (luisbazdev)
 */

import express, { Express, Request, Response, NextFunction } from "express";

import bodyParser from "body-parser";
import cookieParser from "cookie-parser";

import uniqid from "uniqid";

interface IUser{
    email: String,
    password: String
}

interface ISession{
    sid: String,
    expires: Date
}


var users: IUser[] = [
    {
        email: 'foo@email.com',
        password: 'qwerty'
    }
]

/**
 * Since I'm using an array for storing all the user sessions
 * and not an actual database, it means that sessions won't
 * persist and will get lost after the server restarts/stops
 * (not the case for the first user in the users table since
 * it's hardcoded).
 */
var sessions: ISession[] = [];

/**
 * Middleware for '/' route, check if the client has a 'sid'
 * (session) cookie, if yes, check if the session is valid,
 * meaning, it's available in our database, if this is not
 * the case, the user will be redirected to the '/login' route.
 */
function AuthHome(req: Request, res: Response, next: NextFunction){
    var cookie = req.cookies.sid;

    if(cookie){
        // If cookie is set

        // Does the session exist in our sessions table
        var session = sessions.find((session) => session.sid == cookie);

        /**
         * Remove the cookie from the client (log out) in the following scenarios:
         * 
         * 1. The user has a session cookie but the session isn't in our
         * sessions table.
         * 2. The user has a session cookie but the current date is greater
         * than the session expiring date (which means it expired).
         */
        if( (!session) || (session.expires < new Date()) ){
            res.clearCookie('sid');    
            return res.redirect('/login');
        }
    }
    else{
        // If cookie is NOT set
        return res.redirect('/login');
    }    

    next();
}

/**
 * Middleware for '/login' route, check if the client has a 'sid'
 * (session) cookie, if yes, check if the session is valid, meaning,
 * it's available in our database, case which will redirect the user
 * to the '/' protected route.
 */
function AuthLogin(req: Request, res: Response, next: NextFunction){
    var cookie = req.cookies.sid;

    if(cookie)
        // If cookie is set and session is valid
        if(sessions.find((session) => session.sid == cookie))
            return res.redirect('/');
        // If cookie is set and session is NOT valid
        else
            res.clearCookie('sid');

    next();
}

var app: Express = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

app.get('/', AuthHome, (req: Request, res: Response) => {
    res.send(`
    <div>
        <h1>Home page (protected)</h1>
        <form action="/logout" method="POST">
            <button type="submit">logout</button>
        </form>
    </div>`);
})

app.get('/login', AuthLogin, (req: Request, res: Response) => {
    res.send(`
    <div>
        <h1>Login page</h1>
        <form action="/login" method="POST">
            <input type="text" name="email" placeholder="email">
            <input type="text" name="password" placeholder="password">
            <button type="submit">login</button>
        </form>
    </div>`);
})

app.post('/login', (req: Request, res: Response) => {
    var credentials: IUser = req.body;
    
    // If either user or password is wrong
    if(!users.find((user: IUser) => user.email == credentials.email && user.password == credentials.password))
        res.send('Invalid credentials');
    else{
        // Generate ID for the session
        var uuid = uniqid()
    
        /**
         * Store session in our database, both the session record and
         * session cookie will have a max age of 1 minute, after that,
         * the session becomes invalid and the cookie gets deleted from
         * the client, respectively.
         */
        sessions.push({
            sid: uuid,
            expires: new Date(Date.now() + (60 * 1000))
        })
        
        // Set session cookie
        res.cookie('sid', uuid, {
            maxAge: 60 * 1000
        });
        
        res.redirect('/');
    }
})

app.post('/logout', (req: Request, res: Response) => {
    var cookie = req.cookies.sid;

    if(!cookie)
        // If cookie is NOT set
        res.send('You are not logged in');
        
    // Check if session is valid
    var sessionIsValid = sessions.find((session) => session == cookie);

    // If cookie is set and session is valid
    if(sessionIsValid){
        // Remove session from our database
        sessions = sessions.filter((session) => session != sessionIsValid);
    }

    // Remove cookie from the client
    res.clearCookie('sid');

    res.redirect('/login');
})

app.listen(process.env.PORT || 8080);
