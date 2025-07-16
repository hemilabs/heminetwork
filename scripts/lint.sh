#!/bin/sh

EXCLUDED_FILES=$(cat <<-EOF
e2e/output/.+
EOF
)

status_code=0

confirm_y() {
	printf "%s [Y/n]? " "$@"
	read -r answer
	case "$answer" in
		[Nn]*) return 1 ;;  # No
		*)     return 0 ;;  # Yes (default)
	esac
}

fix_file() {
	if [ "$#" -lt 1 ]; then
		echo "fix_file: no file provided"
		exit 1
	fi
	file="$1"

	# Check if the file is excluded.
	for excluded in $EXCLUDED_FILES; do
		if echo "$file" | grep -Eq "$excluded"; then
			return # Excluded
		fi
	done

	# Check file contains trailing newline.
	if [ "$(tail -c 1 "$file" | xxd -p)" != 0a ]; then
		# CI
		if [ "$CI" ]; then
			status_code=1
			line=$(wc -l "$file" | awk '{print $1}')
			line=$((line+1))
			echo "::error file=$file,line=$line,title=Lint::Missing terminating newline"
			return
		fi

		# Auto fix or interactive mode
		if [ "$AUTO_FIX" ] || confirm_y "$file is missing a newline. Fix"; then
			echo >> "$file"
		fi
    fi
}

for file in $(git ls-files); do
	if file --brief --mime-encoding "$file" | grep -qv 'binary'; then
		fix_file "$file"
	fi
done

exit $status_code
