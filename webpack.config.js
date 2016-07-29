const webpack = require('webpack');

module.exports = {
    entry: {
        app: [
            'webpack-hot-middleware/client',
            './client/js/index.jsx'
        ],
        vendor: ['immutable', 'react', 'react-addons-pure-render-mixin', 'react-dom', 'react-redux', 'redux', 'redux-thunk', 'socket.io-client']
    },
    module: {
        loaders: [{
            test: /\.jsx?$/,
            exclude: /node_modules/,
            loader: 'react-hot!babel'
        }, {
            test: /\.less$/,
            loader: 'style!css!less'
        }]
    },
    resolve: {
        extensions: ['', '.js', '.jsx']
    },
    output: {
        path: __dirname + '/dist',
        publicPath: '/',
        filename: 'bundle.js'
    },
    plugins: [
        new webpack.optimize.CommonsChunkPlugin('vendor', 'vendor.bundle.js'),
        new webpack.HotModuleReplacementPlugin()
    ]
};