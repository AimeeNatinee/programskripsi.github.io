$(document).ready(function(){
    $(".btn-stop").prop("disabled",true);
    
    var pathname = window.location.pathname;
    console.log(pathname);
    
    
    if(pathname === '/capturer'){

        var socket = io.connect('http://127.0.0.1:5000/');
        socket.on('capture',function(msg){
            // baca dari server
            let m = JSON.parse(msg);
            console.log(m);
            
            if(m['status'] == 'start'){
                let time = m['time'];
                $('.timeStart').text('Capture paket dimulai pada : '+time);
            }
            else if(m['status'] == 'stop'){
                let time = m['time'];
                $('.timeStop').text('Capture paket dihentikan pada : '+time);
                $('.timeStop').append('<hr color="black">');
            }
            else if(m['capturePacket'] == 'false'){
                let packetNumber = m['jumlahPaket'];
                let info = m['info'];
                $('.packetCaptured').text(packetNumber+' paket berhasil dicapture');
                $('.packetCaptured').append('<p style="color:red;">'+info+'</p>');
            }
            else if(m['status'] == 'proses'){
                let paketAnalisis = m['jumlahPaket'];
                let info = m['info'];
                let value = "Proses Analisis: "+info+"/"+paketAnalisis+" paket.";
                $('.countAnalyzer').text(value);
                if(info == paketAnalisis){
                    window.open('/analyzer');
                }
            }
        });

        socket.on('stopCapture',function(msg){
            let m = JSON.parse(msg);
            console.log(m);
            console.log('capture has stop')
            socket.close();
        });

        $(".btn-start").click(function () {
            console.log('button start click');
            $(".btn-start").prop("disabled",true);
            $(".btn-stop").prop("disabled",false);
            let action={
                'action':'start'
            };
            //kirim ke server json object
            socket.send(JSON.stringify(action));
        });

        $(".btn-stop").click(function (){
            console.log('button stop click');
            $(".btn-stop").prop("disabled",true);
            let action = {
                'action':'stop'
            };
            socket.send(JSON.stringify(action));
        });

    }
    else if(pathname === '/analyzer'){
        console.log("HALAMAN ANALYZER");
        $('#tblAnalyzerPacket').DataTable({
            "responsive": true,
            columnDefs: [{ orderable: false, targets: [1,2,8] }],
        });

        $('#tblAnalyzerBandwidth').DataTable({
            "responsive": true,
            columnDefs: [{ orderable: false ,targets:[1] }],
        });

        $('body').on('click','.paketinfo',function(event){
            var idPaket = $(this).data('id');
            $.ajax({
                url: '/ajaxFile',
                type: 'POST',
                data : {idPaket: idPaket},
                success: function(data){
                    $('.modal-body').html(data);
                    $('.modal-body').append(data.htmlresponse);
                    $('#paketModal').modal('show');
                }
            });
        });
    }
    else if(pathname === '/history/'+pathname.substring(pathname.lastIndexOf('/') + 1)){
        console.log("HALAMAN HISTORY/idWaktu");
        $('#tblDetailHistory').DataTable({
            "responsive": true,
            columnDefs: [{ orderable: false, targets: [1,2,8] }],
        });

        $('#tblAnalyzerBandwidth').DataTable({
            "responsive": true,
            columnDefs: [{ orderable: false, targets: [1] }],
        });

        $('body').on('click','.paketInfoHistory',function(event){
            var idPaket = $(this).data('id');
            $.ajax({
                url: '/ajaxDetailPaketHistory',
                type: 'POST',
                data : {idPaket: idPaket},
                success: function(data){
                    $('.modal-body-history').html(data);
                    $('.modal-body-history').append(data.htmlresponse);
                    $('#paketModalHistory').modal('show');
                }
            });
        });
    }

})





    
