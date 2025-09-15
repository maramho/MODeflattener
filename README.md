# MODeflatten


cd ~/MODeflattener/MODeflattener
python3 -m venv venv
source venv/bin/activate
pip install miasm pyparsing==2.4.7
## python modeflattener.py ... # 실행
pip install angr
pip install pyparsing==2.4.7 --force-reinstall
python -c "import angr, pyparsing; print('angr OK'), print('pyparsing version:', pyparsing.__version__)"


python3 modeflattener.py ./ll_file/cfg_dh_flatten_binary ./ll_file/cfg_dh_2flatten_binary_deflatten 0x1CA8 > dh_2deflatten_log.txt 2>&1


 cfg_dh_2flatten_binary_deflatten된 binary 생성 - > dh_2deflatten_log 로그 확인 




