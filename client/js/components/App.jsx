import React from 'react';
import {connect} from 'react-redux';

import * as actions from '../store/actions';
import Map from './Map';

export default class App extends React.Component {
    render () {
        return <Map {...this.props} />;
    }
};

export const AppContainer = connect((state) => state.toJS(), actions)(App);