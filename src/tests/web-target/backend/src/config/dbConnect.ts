import { Client } from "pg" ;

export default async function dbConnect():Promise<Client>{
    try{
        // console.log("Host:", process.env.PG_HOST);
        // console.log("Port:", Number(process.env.PG_PORT));
        // console.log("User:", process.env.PG_USER);
        // console.log("Password:", process.env.PG_PASSWORD);
        // console.log("Database:", process.env.PG_DB);
        const client:Client = new Client({
            user: process.env.PG_USER,
            database: process.env.PG_DB,
            port: Number(process.env.PG_PORT),
            password: process.env.PG_PASSWORD,
            host: process.env.PG_HOST,
            // ssl: { rejectUnauthorized: false },
            // ssl: true,
        })
        await client.connect();
        return client ;
    }catch(error){
        console.log(error);
        throw "error";
    }
}