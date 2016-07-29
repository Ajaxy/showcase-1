import React from 'react';
import ReactDOM from 'react-dom';
import {Provider} from 'react-redux';

import configureStore from './store/configureStore'
import * as actions from './actions';
import socket from './tools/socket';
import App from './containers/App';

import styles from '../styles/global.less';

const store = configureStore();
store.dispatch(actions.loadSpot());

socket
    .on('spotcreate', (data) => store.dispatch(actions.createInSpots(data.id, data.spot)))
    .on('spotupdate', (data) => store.dispatch(actions.updateInSpots(data.id, data.spot)))
    .on('spotremove', (data) => store.dispatch(actions.removeFromSpots(data.id)));

ReactDOM.render(
    <Provider store={store}>
        <App />
    </Provider>,
    document.getElementById('app')
);
