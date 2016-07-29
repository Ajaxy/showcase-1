import path from 'path';
import mongoose from 'mongoose';
import express from 'express';

import webpack from 'webpack';
import webpackDevMiddleware from 'webpack-dev-middleware';
import webpackHotMiddleware from 'webpack-hot-middleware';

import webpackConfig from '../webpack.config';
import io from './tools/io';

setupDb();
setupExpress();
io.setup();

function setupDb () {
    mongoose.Promise = Promise;
    mongoose.connect('mongodb://localhost:27017/production', (err) => {
        if (err) {
            console.error(err);
        } else {
            console.log('MongoDB connected.');
        }
    });
}

function setupExpress () {
    const clientDir = path.resolve(__dirname, '../dist');
    const compiler = webpack(webpackConfig);

    express()
        .use(webpackDevMiddleware(compiler, { noInfo: true, publicPath: webpackConfig.output.publicPath }))
        .use(webpackHotMiddleware(compiler))
        .use('/', express.static(`${clientDir}/index.html`))
        .use('/donor/*', express.static(`${clientDir}/index.html`))
        .use(express.static(clientDir))
        .listen(8080, (err) => {
            if (err) {
                console.error(error)
            } else {
                console.log('Express is ready. Open http://localhost:8080 in browser.');
            }
        });
}