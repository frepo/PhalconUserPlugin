<?php
namespace Phalcon\UserPlugin\Models\User;

class UserMeta extends \Phalcon\Mvc\Model
{
	/**
	 * 
	 * @var integer
	 */
	protected $id;

	/**
	 * 
	 * @var integer
	 */
	protected $user_id;

	/**
	 * 
	 * @var string
	 */
	protected $key;

	/**
	 * 
	 * @var string
	 */
	protected $value;

	/**
	 * Method to set the value of id
	 * 
	 * @param integer $id 
	 * @return $this
	 */
	public function setId($id)
	{
		$this->id = $id;

		return $this;
	}

	/**
	 * Method to set the value of user_id
	 * 
	 * @param integer $user_id 
	 * @return $this
	 */
	public function setUserId($user_id)
	{
		$this->user_id = $user_id;

		return $this;
	}

	/**
	 * Method to set the value of key
	 * 
	 * @param string $key 
	 * @return $this
	 */
	public function setKey($key)
	{
		$this->key = $key;

		return $this;
	}

	/**
	 * Method to set the value of value
	 * 
	 * @param string $value 
	 * @return $this
	 */
	public function setValue($value)
	{
		$this->value = $value;

		return $this;
	}

	public function getId()
	{
		return $this->id;
	}

	public function getUserId()
	{
		return $this->user_id;
	}

	public function getKey()
	{
		return $this->key;
	}

	public function getValue()
	{
		return $this->value;
	}

	public function initialize()
	{
		$this->belongsTo('user_id', 'Phalcon\UserPlugin\Models\User\User', 'id', array(
			'alias' => 'user',
			'reusable' => true,
		));
	}

	public function getSource()
	{
		return 'user_meta';
	}
}