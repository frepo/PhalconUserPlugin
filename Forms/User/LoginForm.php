<?php
namespace Phalcon\UserPlugin\Forms\User;

use Phalcon\Forms\Form,
Phalcon\Forms\Element\Text,
Phalcon\Forms\Element\Password,
Phalcon\Forms\Element\Submit,
Phalcon\Forms\Element\Check,
Phalcon\Forms\Element\Hidden,
Phalcon\Validation\Validator\PresenceOf,
Phalcon\Validation\Validator\Email,
Phalcon\Validation\Validator\Identical;

/**
 * Phalcon\UserPlugin\Forms\User\LoginForm
 */
class LoginForm extends Form
{
    public function initialize()
    {
        $translate = $this->getDI()->get('translate');
        //Email
        $email = new Text('email', array(
            'placeholder' => $translate->_('Email')
        ));

        $email->addValidators(array(
            new PresenceOf(array(
                'message' => $translate->_('The e-mail is required')
            )),
            new Email(array(
                'message' => $translate->_('The e-mail is not valid')
            ))
        ));

        $this->add($email);

        //Password
        $password = new Password('password', array(
            'placeholder' => $translate->_('Password')
        ));

        $password->addValidator(
            new PresenceOf(array(
                'message' => $translate->_('The password is required')
            ))
        );

        $this->add($password);

        //Remember
        $remember = new Check('remember', array(
            'value' => 'yes'
        ));

        $remember->setLabel($translate->_('Remember me'));

        $this->add($remember);

        //CSRF
        $csrf = new Hidden('csrf');

        $csrf->addValidator(
            new Identical(array(
                'value' => $this->security->getSessionToken(),
                'message' => $translate->_('CSRF validation failed'),
            ))
        );

        $this->add($csrf);

        $this->add(new Submit('go', array(
            'class' => 'btn btn-success'
        )));
    }
}
