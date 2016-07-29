import React from 'react';

import config from '../../../common/config';
import styles from '../../styles/components/BecomeDonor.less';

export default class BecomeDonor extends React.Component {
    onClick (e) {
        if (!this.props.spot) {
            e.preventDefault();
            this.props.setMode(config.MODE_DONOR);
        }
    }
    
    getText () {
        if (this.props.mode != config.MODE_DONOR) {
            return 'Become a donor';
        } else {
            return 'Click on map to set spot...';
        }
    }
    
    render () {
        let classNames = [styles['become-donor'], 'esri-widget', 'esri-widget-button'];
        
        if (this.props.mode == config.MODE_DONOR) {
            classNames.push(styles['disabled']);
        }
        
        return (
            <div className={classNames.join(' ')}
               onClick={this.onClick.bind(this)}
            >{this.getText()}</div>
        );
    }
}