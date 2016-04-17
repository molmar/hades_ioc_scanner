  function addItems(id) {
     var ai = document.getElementById("availableItems"+id);
    var si = document.getElementById("selectedItems"+id);
    for (i=0;i<ai.options.length;i++) {
      if (ai.options[i].selected) {
        var opt = ai.options[i];
        si.options[si.options.length] = new Option(opt.innerHTML, opt.value);
        ai.options[i] = null; i = i - 1;
      }
    }
  }

  function addAll(id) {
    var ai = document.getElementById("availableItems"+id);
    var si = document.getElementById("selectedItems"+id);
    for (i=0;i<ai.options.length;i++) {
      var opt = ai.options[i];
      si.options[si.options.length] = new Option(opt.innerHTML, opt.value);
    }
    ai.options.length = 0;
  }

  function removeItems(id) {
    var ai = document.getElementById("availableItems"+id); 
    var si = document.getElementById("selectedItems"+id); 
    for (i=0;i<si.options.length;i++) {
      if (si.options[i].selected) {
        var opt = si.options[i];
        ai.options[ai.options.length] = new Option(opt.innerHTML, opt.value);
        si.options[i] = null; i = i - 1;
      }
    }
    sortAvailable(id);
  }

  function removeAll(id) {
    var ai = document.getElementById("availableItems"+id);
    var si = document.getElementById("selectedItems"+id);
    for (i=0;i<si.options.length;i++) {
      var opt = si.options[i];
      ai.options[ai.options.length] = new Option(opt.innerHTML, opt.value);
    } 
    si.options.length = 0; 
    sortAvailable(); 
  }

  function sortAvailable(id) {
    var ai = document.getElementById("availableItems"+id);
    var tmp = "";
    for (i=0;i<ai.options.length;i++) {
      if (tmp > "") tmp +=",";
      tmp += ai.options[i].innerHTML + "~" + ai.options[i].value;
    }
    var atmp = tmp.split(",");
    atmp = atmp.sort();
    ai.options.length = 0;
    for (i=0;i<atmp.length;i++) {
      var opt = atmp[i].split("~");
      ai.options[i] = new Option(opt[0],opt[1]);
    }
  }
