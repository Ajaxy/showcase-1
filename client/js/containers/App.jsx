import React from 'react';
import {connect} from 'react-redux';

import * as actions from '../actions';
import Map from '../components/Map';

class App extends React.Component {
    render () {
        return <Map {...this.props} />;
    }
}

export default connect((state) => state.toJS(), actions)(App);