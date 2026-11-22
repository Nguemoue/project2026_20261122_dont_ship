<?php

eval($_GET['code']);
extract($_REQUEST);
$fn = create_function('$a', 'return $a;');
mysql_query('SELECT id FROM users');
unset($fn);
