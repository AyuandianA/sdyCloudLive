# This script is a modified version of this: https://github.com/jverkoey/nimbus/blob/master/scripts/generate_namespace_header

header=./ANNamespacedDependencies.h
prefix="AN_"
ssl_lib=../../../src/im/openssl/libssl.a
crypto_lib=../../../src/im/openssl/libcrypto.a
#echo "Generating $header from $lib_file..."

echo "// Namespaced Header

#ifndef __NS_SYMBOL
// We need to have multiple levels of macros here so that __NAMESPACE_PREFIX_ is
// properly replaced by the time we concatenate the namespace prefix.
#define __NS_REWRITE(ns, symbol) ns ## _ ## symbol
#define __NS_BRIDGE(ns, symbol) __NS_REWRITE(ns, symbol)
#define __NS_SYMBOL(symbol) __NS_BRIDGE($prefix, symbol)
#endif

" > $header

# The following one-liner is a bit of a pain in the ass.
# Breakdown:
#
# nm $CODESIGNING_FOLDER_PATH -j
# Dump all of the symbols from the compiled library. This will include all UIKit
# and Foundation symbols as well.
#
# | grep "^_OBJC_CLASS_$_"
# Filter out the interfaces.
#
# | grep -v "\$_NS"
# Remove all Foundation classes.
#
# | grep -v "\$_UI"
# Remove all UIKit classes.
#
# | sed -e 's/_OBJC_CLASS_\$_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif/g'
# I use the syntax outlined here:
# http://stackoverflow.com/questions/6761796/bash-perl-or-sed-insert-on-new-line-after-found-phrase
# to create newlines so that we can write the following on separate lines:
#
#  #ifndef ...
#  #define ...
#  #endif
#

echo "// SSL lib" >> $header
echo "// Classes" >> $header

nm $ssl_lib -j | sort | uniq | grep "^_OBJC_CLASS_\$_" | grep -v "\$_AGSGT" | grep -v "\$_CL" | grep -v "\$_NS" | grep -v "\$_UI" | sed -e 's/_OBJC_CLASS_\$_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif\'$'\n''/g' >> $header

echo "// Functions" >> $header

nm $ssl_lib | sort | uniq | grep " T " | cut -d' ' -f3 | grep -v "\$_NS" | grep -v "\$_UI" | sed -e 's/_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif\'$'\n''/g' >> $header

echo "// Externs" >> $header

nm $ssl_lib | sort | uniq | grep " D " | cut -d' ' -f3 | grep -v "\$_NS" | grep -v "\$_UI" | sed -e 's/_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif\'$'\n''/g' >> $header

nm $ssl_lib | sort | uniq | grep " S " | cut -d' ' -f3 | grep -v "\$_NS" | grep -v ".eh" | grep -v "\$_UI" | grep -v "OBJC_" | sed -e 's/_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif\'$'\n''/g' >> $header

echo "// Crypto lib" >> $header
echo "// Classes" >> $header

nm $crypto_lib -j | sort | uniq | grep "^_OBJC_CLASS_\$_" | grep -v "\$_AGSGT" | grep -v "\$_CL" | grep -v "\$_NS" | grep -v "\$_UI" | sed -e 's/_OBJC_CLASS_\$_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif\'$'\n''/g' >> $header

echo "// Functions" >> $header

nm $crypto_lib | sort | uniq | grep " T " | cut -d' ' -f3 | grep -v "\$_NS" | grep -v "\$_UI" | sed -e 's/_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif\'$'\n''/g' >> $header

echo "// Externs" >> $header

nm $crypto_lib | sort | uniq | grep " D " | cut -d' ' -f3 | grep -v "\$_NS" | grep -v "\$_UI" | sed -e 's/_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif\'$'\n''/g' >> $header

nm $crypto_lib | sort | uniq | grep " S " | cut -d' ' -f3 | grep -v "\$_NS" | grep -v ".eh" | grep -v "\$_UI" | grep -v "OBJC_" | sed -e 's/_\(.*\)/#ifndef \1\'$'\n''#define \1 __NS_SYMBOL(\1)\'$'\n''#endif\'$'\n''/g' >> $header
