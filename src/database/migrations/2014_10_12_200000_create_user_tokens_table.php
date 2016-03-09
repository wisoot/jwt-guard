<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateUserTokensTable extends Migration
{
    /**
     * @var        string    $table    Table name.
     */
    protected $table;

    /**
     * @var        string    $foreignKey    Column name for foreign keys.
     */
    protected $foreignKey;

    /**
     * Initialise the migration.
     *
     * @return    void
     */
    public function __construct()
    {
        $this->table = $this->config('token_table');

        $this->foreignKey = $this->config('user_foreign_key');
    }

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create($this->table, function (Blueprint $table) {
            $table->increments('id');
            $table->integer($this->foreignKey)->unsigned();
            $table->string('token')->index();
            $table->timestamps();

            $table->foreign($this->foreignKey)->references('id')->on('users');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop($this->table);
    }

    /**
     * Retrieve a setting from the package configuration.
     *
     * @param    string    $key
     * @param    mixed    $default
     * @return    mixed
     */
    private function config($key, $default = null)
    {
        return config("jwt_guard.{$key}", $default);
    }
}
