alias image_list="incus image list | awk '{print \$2}' | grep --invert-match \| | grep --invert-match ALIAS"
alias container_list="incus list | awk '{print \$2}' | grep --invert-match \| | grep --invert-match NAME"
