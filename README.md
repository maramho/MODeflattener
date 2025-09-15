# MODeflatten


# 실행 방법
cd ~/MODeflattener/MODeflattener

python3 -m venv venv

source venv/bin/activate

python3 modeflattener.py ./ll_file/cfg_dh_flatten_binary ./ll_file/cfg_dh_2flatten_binary_deflatten 0x1CA8 > dh_2deflatten_log.txt 2>&1


 cfg_dh_2flatten_binary_deflatten된 binary 생성 - > dh_2deflatten_log 로그 확인 

여기 두개 파일 수정해서 이 두개 보면 됌

MODeflattener/MODeflattener/modeflattener.py

MODeflattener/MODeflattener/mod_utils.py




