import path from 'path';
import mongoose from 'mongoose';
import express from 'express';

import io from './tools/io';

setupDb();
setupExpress();

function setupDb () {
    mongoose.Promise = Promise;
    mongoose.connect('mongodb://localhost:27017/production', (err) => {
        if (err) {
            console.error(err);
        }
    });
}

function setupExpress () {
    const clientDir = path.resolve(__dirname, '../dist');

    express()
        .use('/', express.static(`${clientDir}/index.html`))
        .use('/donor/*', express.static(`${clientDir}/index.html`))
        .use(express.static(clientDir))
        .listen(8085, () => { console.log('Listening port 8085'); });
}