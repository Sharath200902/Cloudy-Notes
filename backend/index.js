const nodemon = require('nodemon');
const connectToMongo = require('./db');
const express = require('express')
connectToMongo();
const app = express()
app.use(express.json());//middleware

const port = 5000

//available routes
app.use('/api/auth', require('./routes/auth'))
app.use('/api/notes', require('./routes/notes'))
app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})