requires 'perl',            5.008008;
requires 'Moo',             2.005004;
requires 'strictures',      2.000006;
requires 'Types::Standard', 1.012004;
requires 'Digest::SHA',     5.96;

on 'test' => sub {
    requires 'Test::More', 0.98;
    recommends 'Crypt::PasswdMD5', 1.40;

};
