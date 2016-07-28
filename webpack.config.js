const webpack = require('webpack');

module.exports = {
    entry: {
        app: [
            'webpack-dev-server/client?http://localhost:8080',
            'webpack/hot/only-dev-server',
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
    externals: [
        function (context, request, callback) {
            if (/^(dojo|dijit|esri)/.test(request)) {
                return callback(null, 'amd ' + request);
            }

            callback();
        }
    ],
    output: {
        path: __dirname + '/dist',
        publicPath: '/',
        filename: 'bundle.js'
    },
    devServer: {
        contentBase: './dist'
    },
    plugins: [
        new webpack.optimize.CommonsChunkPlugin('vendor', 'vendor.bundle.js'),
        new webpack.HotModuleReplacementPlugin()
    ]
};