/*
 * contents: String#countc method.
 *
 * Copyright © 2006 Nikolai Weibull <now@bitwi.se>
 */

#include <ruby.h>

static VALUE
str_countc(VALUE str, VALUE c, VALUE pos, VALUE end)
{
        long count = 0;
        StringValue(c);
        char check = RSTRING(c)->ptr[0];
        char *s = RSTRING(str)->ptr + FIX2INT(pos);
        char *e = RSTRING(str)->ptr + FIX2INT(end);

        while (s < e)
                if (*s++ == check)
                        count++;

        return LONG2FIX(count);
}

void
Init_countc(void)
{
        rb_define_method(rb_cString, "countc", str_countc, 3);
}
