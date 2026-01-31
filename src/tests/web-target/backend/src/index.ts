import express, { Express } from 'express';
import path from 'path';
import 'dotenv/config';
import cors from 'cors';
import dbConnect from './config/dbConnect';

const routes: Express = express();
routes.use(cors()).use(express.json()).use(express.urlencoded());

routes.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  console.log(username, password);
  const client = await dbConnect();
  const result = await client.query(
    'SELECT * FROM login WHERE username = $1 AND password = $2',
    [username, password]
  );
  if (result.rows.length > 0) {
    res.status(200).json({
      message: 'Login successful',
      user: result.rows[0]
    });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// http://192.168.122.109:5000/api/file?filename=../../../../../../../../../../../../etc/passwd
routes.get('/api/file', (req, res) => {
  const { filename } = req.query;
  const filesDirectory = path.join(process.cwd(), 'src/', 'files');
  const filePath = path.join(filesDirectory, String(filename));
  res.sendFile(filePath);
});

// http://192.168.122.109:5000/api/file/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
routes.get('/api/file/:filename', (req, res) => {
  const { filename } = req.params;
  const filesDirectory = path.join(process.cwd(), 'src/', 'files');
  const filePath = path.join(filesDirectory, String(filename));
  res.sendFile(filePath);
});

routes.listen(5000);