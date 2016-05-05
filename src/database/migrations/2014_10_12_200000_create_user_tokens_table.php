<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;

class CreateUserTokensTable extends Migration
{

    /**
     * @var string $tableName - Table name.
     */
    protected $tableName;

    /**
     * Initialise the migration.
     */
    public function __construct()
    {
        $this->tableName = Config::get('jwt.claim_table_name');
    }

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create($this->tableName, function (Blueprint $table) {
            $table->increments('id');
            $table->string('subject')->unsigned();
            $table->string('audience')->unsigned();
            $table->string('jwt_id')->index();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop($this->tableName);
    }

}
