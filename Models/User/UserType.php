<?php

namespace Phalcon\UserPlugin\Models\User;

class UserType extends \Phalcon\Mvc\Model
{
	protected $id;

	protected $title;

	protected $enabled = 1;

	protected $banned = 0;

	protected $visible = 1;

	public function setId($id)
	{
		$this->id = (int) $id;

		return $this;
	}

	public function setTitle($title)
	{
		$this->title = $title;

		return $this;
	}

	public function setEnabled($enabled)
	{
		$this->enabled = (bool) $enabled;

		return $this;
	}

	public function setBanned($banned)
	{
		$this->banned = (bool) $banned;
	}

	public function setVisible($visible)
	{
		$this->visible = (bool) $visible;
	}
}