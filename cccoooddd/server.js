const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const app = express();
const PORT = 3000;

app.use(bodyParser.json());

app.post('/save', (req, res) => {
    const data = req.body;
    fs.appendFileSync('data.txt', JSON.stringify(data) + '\n');
    res.send({status: 'ok'});
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});