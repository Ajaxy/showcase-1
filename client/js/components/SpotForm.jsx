import React from 'react';

import config from '../../../common/config';
import styles from '../../styles/components/SpotForm.less';

export default class SpotForm extends React.Component {
    constructor () {
        super();
        this.state = {
            firstName: '',
            lastName: '',
            contactNumber: '',
            email: '',
            bloodGroup: ''
        };
    }

    componentWillReceiveProps (nextProps) {
        if (nextProps.spot) {
            let state = {};

            Object.keys(this.state).forEach((name) => {
                state[name] = nextProps.spot[name];
            });

            this.setState(state);
        }
    }

    handleSubmit (e) {
        e.preventDefault();

        if (this.props.spot) {
            this.props.updateSpot(this.state);
        } else {
            this.props.createSpot(this.state);
        }

        return false;
    }

    handleChange (e) {
        let { name, value } = e.target;

        if (name == 'contactNumber') {
            value = value
                .replace(/[^\d]/g, '')
                .replace(/^(([0]{2})?([1-9]){2})/, '$1 ')
                .replace(/( \d{3})/, '$1 ')
                .replace(/( \d{4})/, '$1 ')
                .replace(/\s$/, '');

            if (value[0] != '0') {
                value = '+' + value;
            }
        }

        this.setState({ [name]: value });
    }

    handleDelete (e) {
        if (confirm('Are you sure?')) {
            this.props.removeSpot();
            this.props.onRemoveSpot();
        }
    }

    render () {
        const classNames = [styles['form']];

        if (this.props.mode != config.MODE_DONOR) {
            classNames.push('hidden');
        }

        return (
            <form className={classNames.join(' ')} onSubmit={this.handleSubmit.bind(this)}>
                {this.props.spot ? <div className={styles['success']}>Thank you!</div> : ''}
                <input type="text"
                       name="firstName"
                       placeholder="First name"
                       value={this.state.firstName}
                       onChange={this.handleChange.bind(this)}
                       required
                />
                <input type="text"
                       name="lastName"
                       placeholder="Last name"
                       value={this.state.lastName}
                       onChange={this.handleChange.bind(this)}
                       required
                />
                <div className="clearfix"></div>
                <input type="tel"
                       name="contactNumber"
                       placeholder="+12 345 6789 012"
                       pattern="^(00|\+)\d{2} \d{3} \d{4} \d{3}$"
                       maxLength="17"
                       value={this.state.contactNumber}
                       onChange={this.handleChange.bind(this)}
                       required
                />
                <input type="email"
                       name="email"
                       placeholder="E-mail"
                       value={this.state.email}
                       onChange={this.handleChange.bind(this)}
                       required
                />
                <div className="clearfix"></div>
                <span>Blood group:</span>
                <input type="number"
                       name="bloodGroup"
                       placeholder="1"
                       value={this.state.bloodGroup}
                       onChange={this.handleChange.bind(this)}
                       required
                       className={styles['blood-group']}
                    {...config.BLOOD_GROUP_RANGE}
                />
                <div className="clearfix"></div>
                <input type="submit"
                       value={this.props.spot ? 'Update donor spot' : 'Create donor spot'}
                       className={styles['submit']}
                />
                {this.props.spot ?
                    <input type="button"
                           value="Delete spot"
                           onClick={this.handleDelete.bind(this)}
                           className={styles['submit']}
                    />
                    : ''}
                
            </form>
        );
    }
};